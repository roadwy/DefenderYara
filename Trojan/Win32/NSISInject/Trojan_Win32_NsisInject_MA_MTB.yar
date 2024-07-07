
rule Trojan_Win32_NsisInject_MA_MTB{
	meta:
		description = "Trojan:Win32/NsisInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 e4 03 55 f8 0f b6 02 33 c1 8b 4d e4 03 4d f8 88 01 8b 55 f8 83 c2 01 89 55 f8 eb c8 8d 45 e0 50 6a 40 8b 4d e8 51 8b 55 e4 52 ff 15 90 01 04 ff 55 e4 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}