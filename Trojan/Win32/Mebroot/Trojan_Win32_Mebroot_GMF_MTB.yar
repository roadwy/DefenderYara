
rule Trojan_Win32_Mebroot_GMF_MTB{
	meta:
		description = "Trojan:Win32/Mebroot.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 00 8b 70 08 8b 46 3c 8b 44 30 78 03 c6 8b 78 20 03 fe 83 65 f4 00 c7 45 ?? 47 65 74 50 c7 45 ?? 72 6f 63 41 c7 45 ?? 64 64 72 65 c7 45 ?? 73 73 00 00 8b 4d f4 8b 14 8f 03 d6 ff 45 f4 8d 4d d8 89 4d ec 0f b6 0a 83 e9 47 } //10
		$a_01_1 = {25 73 69 62 6d 25 30 35 64 2e 64 6c 6c } //1 %sibm%05d.dll
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}