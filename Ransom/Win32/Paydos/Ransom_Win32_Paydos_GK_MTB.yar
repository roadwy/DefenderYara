
rule Ransom_Win32_Paydos_GK_MTB{
	meta:
		description = "Ransom:Win32/Paydos.GK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 f1 81 e6 ff 00 00 00 c1 e9 08 33 0c b5 58 15 41 00 0f b6 70 04 33 f1 81 e6 ff 00 00 00 c1 e9 08 33 0c b5 58 15 41 00 0f b6 70 05 33 f1 81 e6 ff 00 00 00 c1 e9 08 33 0c b5 58 15 41 00 0f b6 70 06 33 f1 81 e6 ff 00 00 00 c1 e9 08 } //1
		$a_01_1 = {73 65 74 20 5f 70 61 73 73 43 6f 64 65 3d 41 45 53 31 30 31 34 44 57 32 35 36 } //1 set _passCode=AES1014DW256
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}