
rule Trojan_BAT_Stealer_AYD_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AYD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 03 17 8d 06 00 00 01 25 16 09 20 bf 24 0a 00 d6 8c 4c 00 00 01 a2 14 28 6c 00 00 0a 28 6d 00 00 0a 6f 6e 00 00 0a 00 09 17 d6 0d 09 08 31 d0 } //2
		$a_01_1 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e } //1 DebuggerHidden
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}