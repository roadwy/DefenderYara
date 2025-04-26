
rule Trojan_Win32_Adload_EA{
	meta:
		description = "Trojan:Win32/Adload.EA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {be 00 40 00 00 8d ?? ?? ?? b8 ff 00 00 00 e8 ?? ?? ?? ?? 88 03 43 4e 75 f0 8d ?? ?? ?? b9 00 40 00 00 8b ?? ?? 8b 18 ff 53 10 4f 75 d3 } //3
		$a_00_1 = {2e 61 73 61 69 63 61 63 68 65 2e 63 6f 6d 3a } //1 .asaicache.com:
		$a_00_2 = {2e 68 65 74 6f 64 6f 2e 63 6f 6d 3a } //1 .hetodo.com:
		$a_00_3 = {5f 63 68 2e 70 68 70 3f 75 69 64 3d 25 73 } //1 _ch.php?uid=%s
		$a_00_4 = {2f 72 65 2e 70 68 70 3f 6b 65 79 3d 25 73 26 76 65 72 3d 25 73 26 75 69 64 3d 25 73 } //1 /re.php?key=%s&ver=%s&uid=%s
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}