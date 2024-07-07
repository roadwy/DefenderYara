
rule Trojan_BAT_Renerez_AKV_MTB{
	meta:
		description = "Trojan:BAT/Renerez.AKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {6d 73 63 6f 72 6a 69 74 2e 64 6c 6c } //mscorjit.dll  1
		$a_00_1 = {46 00 72 00 65 00 65 00 6d 00 61 00 6b 00 65 00 20 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 73 00 20 00 4b 00 65 00 79 00 67 00 65 00 6e 00 20 00 62 00 79 00 20 00 47 00 6f 00 32 00 43 00 72 00 63 00 6b 00 40 00 54 00 65 00 61 00 6d 00 2e 00 65 00 78 00 65 00 } //1 Freemake Products Keygen by Go2Crck@Team.exe
		$a_00_2 = {47 00 6f 00 32 00 43 00 72 00 63 00 6b 00 40 00 54 00 65 00 61 00 6d 00 } //1 Go2Crck@Team
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}