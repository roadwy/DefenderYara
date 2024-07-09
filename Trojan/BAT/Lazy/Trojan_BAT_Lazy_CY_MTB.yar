
rule Trojan_BAT_Lazy_CY_MTB{
	meta:
		description = "Trojan:BAT/Lazy.CY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 6f 3a 00 00 0a 0c 08 28 ?? ?? 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a 0c 08 17 8d ?? ?? 00 01 25 16 1f 0d 9d 6f ?? ?? 00 0a 0c 02 08 17 8d ?? ?? 00 01 25 16 1f 0d 9d 6f ?? ?? 00 0a 7d ?? ?? 00 04 02 7b ?? ?? 00 04 0d 16 13 04 2b 18 } //5
		$a_01_1 = {73 68 69 70 69 6e 66 6f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 shipinfo.Properties.Resources
		$a_01_2 = {77 72 69 74 65 66 69 6c 65 } //1 writefile
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}