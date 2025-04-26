
rule Trojan_Win32_FolSoc_A_MTB{
	meta:
		description = "Trojan:Win32/FolSoc.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 56 57 8b 7d 08 8b 75 0c 8b 4d 10 f3 a4 5f 5e 5d c2 0c } //2
		$a_03_1 = {6a 00 68 00 20 00 00 8d 84 24 c0 01 00 00 50 ff 35 3c 45 40 00 ff 15 64 30 40 00 85 c0 0f 8e ?? ?? ?? ?? 50 8d 8c 24 bc 01 00 00 51 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 03 ce 51 8b cf } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}