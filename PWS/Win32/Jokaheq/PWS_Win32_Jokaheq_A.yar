
rule PWS_Win32_Jokaheq_A{
	meta:
		description = "PWS:Win32/Jokaheq.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {2f 2f 65 76 65 72 65 73 74 73 65 72 72 61 2d 72 75 2e 31 67 62 2e 72 75 2f 4d 61 72 63 61 64 6f 72 2f 70 6f 73 74 2e 70 68 70 } ////everestserra-ru.1gb.ru/Marcador/post.php  3
		$a_00_1 = {53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 4b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00 20 00 4c 00 61 00 79 00 6f 00 75 00 74 00 73 00 5c 00 25 00 2e 00 38 00 78 00 } //1 System\CurrentControlSet\Control\Keyboard Layouts\%.8x
		$a_00_2 = {58 00 2d 00 48 00 54 00 54 00 50 00 2d 00 4d 00 65 00 74 00 68 00 6f 00 64 00 2d 00 4f 00 76 00 65 00 72 00 72 00 69 00 64 00 65 00 } //1 X-HTTP-Method-Override
	condition:
		((#a_80_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=5
 
}