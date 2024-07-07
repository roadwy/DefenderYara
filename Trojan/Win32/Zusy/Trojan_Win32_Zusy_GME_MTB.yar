
rule Trojan_Win32_Zusy_GME_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 55 08 56 00 f1 8b 06 83 e8 10 90 01 01 00 39 50 08 7d 13 85 d2 00 0f 57 8b 39 6a 01 90 01 01 00 ff 57 08 5f 85 c0 75 00 e8 40 90 00 } //10
		$a_80_1 = {64 6d 63 6f 6d 6d 61 6e 64 65 72 2e 65 78 65 } //dmcommander.exe  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}