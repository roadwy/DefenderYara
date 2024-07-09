
rule Trojan_Win32_TrickBot_DX_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f8 00 00 00 2b [0-12] 6b ?? 29 8b ?? c1 e2 06 [0-04] 8b 54 ?? 3c [0-04] 2b ?? 8b ?? ?? 78 03 [0-03] 8b [0-02] 24 8b [0-02] 20 [0-04] 8d [0-08] 8b ?? 1c 8b ?? 18 [0-08] 03 ?? 03 ?? 03 ?? 03 } //1
		$a_03_1 = {55 8b ec 8b [0-15] c1 ?? 0d 3c 61 0f be c0 7c 03 83 e8 20 [0-04] 03 [0-04] 8a ?? 84 c0 75 ea 8d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}