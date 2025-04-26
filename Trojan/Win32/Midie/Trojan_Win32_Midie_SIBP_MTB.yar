
rule Trojan_Win32_Midie_SIBP_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 6b 78 6c 73 7a 71 6e 2e 64 6c 6c } //1 skxlszqn.dll
		$a_03_1 = {52 6a 40 68 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? b9 00 00 00 00 8a 84 0d 90 1b 01 81 f9 90 1b 00 74 ?? [0-08] 04 ?? 34 ?? [0-08] 04 f7 [0-08] 88 84 0d 90 1b 01 83 c1 01 90 18 8a 84 0d 90 1b 01 81 f9 90 1b 00 90 18 b0 00 b9 00 00 00 00 8d 8d 90 1b 01 ff d1 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}