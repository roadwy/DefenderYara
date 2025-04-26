
rule Trojan_BAT_Stealer_AYC_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 30 11 30 1f 19 62 61 13 30 11 30 11 30 1f 1b 64 61 13 30 11 39 20 48 3c f0 25 5a 20 05 c9 1d 02 61 } //2
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}