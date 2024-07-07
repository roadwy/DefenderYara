
rule Ransom_Win32_Tobfy_W{
	meta:
		description = "Ransom:Win32/Tobfy.W,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 2e 70 68 70 3f 6f 73 3d 25 73 26 61 72 63 68 3d 25 73 26 70 69 6e 3d 25 73 } //1 get.php?os=%s&arch=%s&pin=%s
		$a_01_1 = {64 8b 35 30 00 00 00 8b 76 0c 8b 76 1c 8b 56 08 8b 7e 20 8b 36 81 7f 0c 33 00 32 00 75 ef } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}