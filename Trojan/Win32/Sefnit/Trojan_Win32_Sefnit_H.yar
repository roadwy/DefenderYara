
rule Trojan_Win32_Sefnit_H{
	meta:
		description = "Trojan:Win32/Sefnit.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {a9 fe ff ff ff 74 1d 8b 46 24 8b 55 ?? 66 8b 14 4a 8d 04 48 66 31 10 8b 45 ?? 2b 45 ?? 41 d1 f8 3b c8 75 e3 } //2
		$a_01_1 = {67 65 74 74 61 73 6b 73 2e 70 68 70 3f 70 72 6f 74 6f 63 6f 6c 3d } //1 gettasks.php?protocol=
		$a_01_2 = {5c 64 61 69 6c 79 2d 62 61 63 6b 64 6f 6f 72 2d 73 74 61 62 6c 65 2d 65 64 32 6b } //1 \daily-backdoor-stable-ed2k
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}