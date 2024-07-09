
rule Trojan_Win32_QakBot_MT_MTB{
	meta:
		description = "Trojan:Win32/QakBot.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 08 5d c3 90 0a 30 00 31 0d ?? ?? ?? ?? eb 00 c7 05 [0-08] a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d } //1
		$a_01_1 = {63 00 3a 00 5c 00 6d 00 69 00 72 00 63 00 5c 00 6d 00 69 00 72 00 63 00 2e 00 69 00 6e 00 69 00 } //1 c:\mirc\mirc.ini
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}