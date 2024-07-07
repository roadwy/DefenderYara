
rule Trojan_Win32_IcedId_DEB_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 10 33 f6 8d 44 24 10 56 6a 01 5d 55 56 56 50 ff 15 90 01 04 85 c0 5b 75 36 6a 08 55 56 8d 44 24 18 56 50 ff 15 90 1b 00 85 c0 90 00 } //1
		$a_81_1 = {52 59 78 68 68 75 67 35 6f 70 35 65 30 6e 68 } //1 RYxhhug5op5e0nh
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}