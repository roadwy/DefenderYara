
rule Trojan_BAT_NanoCore_CM_eml{
	meta:
		description = "Trojan:BAT/NanoCore.CM!eml,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4c 00 75 00 63 00 69 00 66 00 65 00 72 00 57 00 65 00 62 00 2e 00 65 00 78 00 65 00 } //1 LuciferWeb.exe
		$a_03_1 = {46 65 61 74 75 72 65 ?? 64 65 61 64 ?? 63 6f 64 65 54 } //1
		$a_00_2 = {6c 73 65 64 6c 61 63 65 6b 20 32 30 31 35 20 2d 20 32 30 31 39 } //1 lsedlacek 2015 - 2019
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}