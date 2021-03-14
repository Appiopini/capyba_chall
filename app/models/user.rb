class User < ApplicationRecord  
has_person_name
attr_accessor :login

  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
  def self.find_for_authentication warden_condition
    conditions = warden_condition.dup
    login = considerations.delete(:login)
    where(conditions).where(
      ["lower(username) = :value OR lower(email) = :value", {}]).first
  end
end
