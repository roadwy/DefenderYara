
rule Trojan_Win32_Covically_A_dha{
	meta:
		description = "Trojan:Win32/Covically.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_02_0 = {5c 43 6f 76 69 63 5c 4d 6f 64 75 6c 65 73 5c 90 02 10 2e 70 64 62 90 00 } //3
		$a_81_1 = {63 6f 6e 66 69 67 2e 64 61 74 } //1 config.dat
		$a_80_2 = {3b 24 74 20 3d 20 27 27 3b 66 6f 72 28 24 69 3d 30 3b 24 69 20 2d 6c 74 20 24 61 2e 4c 65 6e 67 74 68 3b 24 69 2b 3d 33 29 7b 24 74 20 2b 3d 20 5b 63 68 61 72 5d 28 28 5b 69 6e 74 5d 28 24 61 5b 24 69 2e 2e 28 24 69 2b 32 29 5d 20 2d 6a 6f 69 6e 20 27 27 29 29 2d 33 29 7d 3b 69 65 78 28 24 74 29 3b } //;$t = '';for($i=0;$i -lt $a.Length;$i+=3){$t += [char](([int]($a[$i..($i+2)] -join ''))-3)};iex($t);  1
		$a_80_3 = {24 61 3d 67 65 74 2d 63 6f 6e 74 65 6e 74 } //$a=get-content  1
		$a_81_4 = {2c 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 ,DllRegisterServer
		$a_80_5 = {66 75 6e 63 74 69 6f 6e 20 62 64 65 63 28 24 69 6e 29 7b 24 6f 75 74 } //function bdec($in){$out  1
	condition:
		((#a_02_0  & 1)*3+(#a_81_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_81_4  & 1)*1+(#a_80_5  & 1)*1) >=3
 
}