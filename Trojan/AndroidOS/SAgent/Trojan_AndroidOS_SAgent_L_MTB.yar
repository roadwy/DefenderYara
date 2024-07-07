
rule Trojan_AndroidOS_SAgent_L_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgent.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 4c 41 54 46 4f 52 4d 5f 53 54 41 52 54 5f 53 4d 53 5f 43 48 41 52 47 45 } //1 PLATFORM_START_SMS_CHARGE
		$a_01_1 = {53 6d 73 54 72 61 6e 73 6d 69 74 5f 25 64 } //1 SmsTransmit_%d
		$a_01_2 = {53 4d 53 5f 42 4c 4f 43 4b 45 44 5f 41 4e 41 4c 59 5a 45 } //1 SMS_BLOCKED_ANALYZE
		$a_01_3 = {53 4d 53 5f 50 52 45 50 41 52 45 5f 53 45 4e 44 } //1 SMS_PREPARE_SEND
		$a_01_4 = {26 63 6f 75 6e 74 65 72 3d 31 26 74 6b 49 6e 66 6f 3d } //1 &counter=1&tkInfo=
		$a_01_5 = {6b 67 71 68 6b 73 5f 64 6f 6d 61 69 6e } //1 kgqhks_domain
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}