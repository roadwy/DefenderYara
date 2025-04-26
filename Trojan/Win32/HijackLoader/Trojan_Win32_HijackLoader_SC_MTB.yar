
rule Trojan_Win32_HijackLoader_SC_MTB{
	meta:
		description = "Trojan:Win32/HijackLoader.SC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 ba 97 ff ff 80 3e 3d 59 8d 58 01 74 22 6a 01 53 e8 f3 c2 ff ff 59 59 89 07 85 c0 74 3f 56 53 50 e8 c8 cc ff ff 83 c4 0c 85 c0 75 47 83 c7 04 03 f3 80 3e 00 75 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}