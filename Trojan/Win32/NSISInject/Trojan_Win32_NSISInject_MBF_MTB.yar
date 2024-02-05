
rule Trojan_Win32_NSISInject_MBF_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.MBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 0c 06 80 c1 7d 80 f1 86 80 c1 58 80 f1 e7 80 c1 77 80 f1 31 80 c1 03 80 f1 d0 fe c1 80 f1 3e 80 c1 43 80 f1 10 fe c1 88 0c 06 40 3b 45 f0 72 } //00 00 
	condition:
		any of ($a_*)
 
}