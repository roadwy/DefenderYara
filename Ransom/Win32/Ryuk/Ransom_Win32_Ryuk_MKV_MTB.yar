
rule Ransom_Win32_Ryuk_MKV_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 33 45 fc 25 ff 00 00 00 8b 4d fc c1 e9 08 33 8c 85 ?? ?? ?? ?? 89 4d fc 8b 55 08 83 c2 01 89 55 08 eb } //1
		$a_01_1 = {24 70 61 73 73 77 6f 72 64 20 3d 20 27 } //1 $password = '
		$a_01_2 = {24 74 6f 72 6c 69 6e 6b 20 3d 20 27 } //1 $torlink = '
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}