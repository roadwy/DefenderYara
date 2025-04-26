
rule Trojan_Win32_LummaStealer_NME_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.NME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {32 37 3e 34 ?? 83 c4 04 5b 69 8d ?? ?? ?? ?? fe 00 00 00 81 c1 3b 66 f3 56 69 95 ?? ?? ?? ?? fe 00 00 00 } //3
		$a_03_1 = {49 4c 39 4f ?? 3e 4c 39 37 45 83 c4 ?? 5b 8b 8d 84 fd ff ff } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}