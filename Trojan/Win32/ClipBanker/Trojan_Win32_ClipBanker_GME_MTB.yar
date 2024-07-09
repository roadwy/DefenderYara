
rule Trojan_Win32_ClipBanker_GME_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 33 c0 c7 05 ?? ?? ?? ?? 0f 00 00 00 a3 ?? ?? ?? ?? a2 ?? ?? ?? ?? c3 c7 05 ?? ?? ?? ?? 54 53 01 10 b9 } //10
		$a_01_1 = {4c 6f 63 61 6c 5c 45 78 69 74 43 6c 69 70 65 72 } //1 Local\ExitCliper
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}