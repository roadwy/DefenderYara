
rule Trojan_Win32_Socelars_PA_MTB{
	meta:
		description = "Trojan:Win32/Socelars.PA!MTB,SIGNATURE_TYPE_PEHSTR,12 00 12 00 12 00 00 "
		
	strings :
		$a_01_0 = {79 00 65 00 73 00 74 00 65 00 72 00 64 00 61 00 79 00 } //1 yesterday
		$a_01_1 = {6d 75 74 65 78 20 64 65 74 65 63 74 65 64 } //1 mutex detected
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 69 70 6c 6f 67 67 65 72 2e 6f 72 67 2f } //1 https://iplogger.org/
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 67 72 61 70 68 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2f 76 34 2e 30 2f 61 63 74 5f } //1 https://graph.facebook.com/v4.0/act_
		$a_01_4 = {70 61 79 6d 65 6e 74 5f 6d 65 74 68 6f 64 5f 73 74 6f 72 65 64 5f 62 61 6c 61 6e 63 65 73 } //1 payment_method_stored_balances
		$a_01_5 = {42 61 63 63 6f 75 6e 74 5f 69 64 } //1 Baccount_id
		$a_01_6 = {63 72 65 64 69 74 5f 63 61 72 64 5f 61 64 64 72 65 73 73 } //1 credit_card_address
		$a_01_7 = {63 75 72 72 65 6e 74 5f 62 61 6c 61 6e 63 65 } //1 current_balance
		$a_01_8 = {70 61 79 6d 65 6e 74 5f 6d 65 74 68 6f 64 5f 70 61 79 70 61 6c } //1 payment_method_paypal
		$a_01_9 = {68 74 74 70 73 3a 2f 2f 73 65 63 75 72 65 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2f 61 64 73 2f 6d 61 6e 61 67 65 72 2f 61 63 63 6f 75 6e 74 5f 73 65 74 74 69 6e 67 73 2f 61 63 63 6f 75 6e 74 5f 62 69 6c 6c 69 6e 67 2f } //1 https://secure.facebook.com/ads/manager/account_settings/account_billing/
		$a_01_10 = {73 65 6c 65 63 74 20 63 6f 75 6e 74 28 2a 29 20 61 73 20 52 43 6f 75 6e 74 20 66 72 6f 6d 20 63 6f 6f 6b 69 65 73 } //1 select count(*) as RCount from cookies
		$a_01_11 = {46 52 4f 4d 20 6d 6f 7a 5f 63 6f 6f 6b 69 65 73 20 77 68 65 72 65 20 68 6f 73 74 3d 27 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 27 3b } //1 FROM moz_cookies where host='.facebook.com';
		$a_01_12 = {73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 6c 6f 67 69 6e 73 20 77 68 65 72 65 20 62 6c 61 63 6b 6c 69 73 74 65 64 5f 62 79 5f 75 73 65 72 3d 30 20 61 6e 64 20 70 72 65 66 65 72 72 65 64 3d 31 20 61 6e 64 20 20 6f 72 69 67 69 6e 5f 75 72 6c 20 6c 69 6b 65 } //1 select * from logins where blacklisted_by_user=0 and preferred=1 and  origin_url like
		$a_01_13 = {64 61 74 72 7c 73 62 7c 63 5f 75 73 65 72 7c 78 73 7c 70 6c 7c 66 72 } //1 datr|sb|c_user|xs|pl|fr
		$a_01_14 = {6e 6f 20 66 62 63 6f 6f 6b 69 65 73 20 66 6f 75 6e 64 } //1 no fbcookies found
		$a_01_15 = {61 6d 61 7a 6f 6e 5f 75 73 } //1 amazon_us
		$a_01_16 = {61 6d 61 7a 6f 6e 5f 75 6b } //1 amazon_uk
		$a_01_17 = {63 5f 75 73 65 72 } //1 c_user
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=18
 
}