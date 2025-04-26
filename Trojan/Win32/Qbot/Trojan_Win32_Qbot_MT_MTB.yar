
rule Trojan_Win32_Qbot_MT_MTB{
	meta:
		description = "Trojan:Win32/Qbot.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec a1 [0-04] a3 [0-04] 90 18 55 8b ec 57 [0-04] a1 [0-04] a3 [0-04] 8b [0-05] 8b [0-04] 89 [0-05] a1 [0-04] 2d [0-04] a3 } //1
		$a_02_1 = {8b ff c7 05 [0-08] 01 05 [0-06] 8b 0d [0-04] 8b 15 [0-04] 89 11 33 c0 e9 90 09 05 00 a1 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}