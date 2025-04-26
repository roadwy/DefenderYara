
rule Trojan_BAT_Giganticus_B_dha{
	meta:
		description = "Trojan:BAT/Giganticus.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_81_0 = {66 34 39 61 64 61 64 34 2d 35 37 36 63 2d 34 63 30 37 2d 39 39 31 31 2d 39 30 66 34 62 39 30 35 38 64 39 32 } //1 f49adad4-576c-4c07-9911-90f4b9058d92
		$a_03_1 = {1f 66 0a 12 00 28 ?? ?? ?? 0a a2 25 17 1f 34 0a 12 00 28 ?? ?? ?? 0a a2 25 18 1f 39 0a 12 00 28 ?? ?? ?? 0a a2 25 19 1f 61 0a 12 00 28 ?? ?? ?? 0a a2 25 1a 1f 64 0a 12 00 28 ?? ?? ?? 0a a2 25 1b 1f 61 0a 12 00 28 ?? ?? ?? 0a a2 25 1c 1f 64 0a 12 00 28 ?? ?? ?? 0a a2 25 1d 1f 34 0a 12 00 28 ?? ?? ?? 0a a2 25 1e 1f 2d 0a 12 00 28 ?? ?? ?? 0a a2 25 1f 09 1f 35 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}