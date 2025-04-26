
rule Trojan_Win32_Padvaw_D{
	meta:
		description = "Trojan:Win32/Padvaw.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b ec 83 c4 fc 60 68 00 10 00 10 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 } //1
		$a_01_1 = {76 0e 68 66 06 00 00 6a 13 6a 00 6a 00 ff 55 f0 83 f8 11 } //2
		$a_01_2 = {73 65 74 75 70 61 70 69 2e 64 6c 6c 00 43 72 65 61 74 65 50 72 6f 63 65 73 73 4e 6f 74 69 66 79 } //2 敳畴慰楰搮汬䌀敲瑡健潲散獳潎楴祦
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}