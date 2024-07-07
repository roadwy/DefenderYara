
rule Ransom_Win32_Lockbit_AK_ibt{
	meta:
		description = "Ransom:Win32/Lockbit.AK!ibt,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 40 10 64 8b 00 8b 40 0c 8d 48 0c 89 4d f8 8b 48 0c 8b 59 18 33 c0 40 c1 e0 05 8d 40 1d 8b 44 03 ff 8d 04 03 8b 50 78 85 d2 } //1
		$a_01_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 68 02 10 04 00 ff d0 8b f0 85 f6 0f 84 7c 01 00 00 8b 40 40 c1 e8 1c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}