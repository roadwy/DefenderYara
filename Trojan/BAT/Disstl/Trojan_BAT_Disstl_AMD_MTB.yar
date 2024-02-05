
rule Trojan_BAT_Disstl_AMD_MTB{
	meta:
		description = "Trojan:BAT/Disstl.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 15 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b 13 06 07 72 90 01 03 70 6f 90 01 03 0a 58 6f 90 01 03 0a 0a 06 72 90 01 03 70 6f 90 01 03 0a 25 0b 15 33 dd 90 00 } //05 00 
		$a_80_1 = {44 69 73 63 6f 72 64 } //Discord  05 00 
		$a_80_2 = {5c 47 72 6f 77 74 6f 70 69 61 5c 73 61 76 65 2e 64 61 74 } //\Growtopia\save.dat  04 00 
		$a_80_3 = {47 65 74 41 6c 6c 4e 65 74 77 6f 72 6b 49 6e 74 65 72 66 61 63 65 73 } //GetAllNetworkInterfaces  04 00 
		$a_80_4 = {55 70 6c 6f 61 64 46 69 6c 65 } //UploadFile  03 00 
		$a_80_5 = {57 65 62 48 6f 6f 6b } //WebHook  00 00 
	condition:
		any of ($a_*)
 
}