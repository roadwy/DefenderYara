
rule Trojan_BAT_AveMaria_NEDA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 35 38 33 38 36 } //10 cc7fad03-816e-432c-9b92-001f2d358386
		$a_01_1 = {73 65 72 76 65 72 31 2e 65 78 65 } //5 server1.exe
		$a_01_2 = {43 6f 6e 66 75 73 65 72 45 78 20 76 31 2e 30 2e 30 } //1 ConfuserEx v1.0.0
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_01_4 = {67 65 74 5f 54 61 72 67 65 74 } //1 get_Target
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=18
 
}