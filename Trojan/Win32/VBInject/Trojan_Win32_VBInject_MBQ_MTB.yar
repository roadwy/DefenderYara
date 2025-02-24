
rule Trojan_Win32_VBInject_MBQ_MTB{
	meta:
		description = "Trojan:Win32/VBInject.MBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fc 22 40 00 00 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 18 22 40 00 10 22 40 00 24 18 40 00 78 00 00 00 81 00 00 00 8a 00 00 00 8b [0-21] 50 72 6f 6a 65 63 74 31 00 50 72 6f 6a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}