
rule Ransom_Win32_Ryuk_BY_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.BY!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 63 20 73 74 6f 70 20 77 69 6e 64 65 66 65 6e 64 } //1 sc stop windefend
		$a_01_1 = {72 75 6e 2f 76 20 6d 73 61 73 63 75 69 2f 66 20 72 65 67 20 64 65 6c 65 74 65 } //1 run/v msascui/f reg delete
		$a_01_2 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 20 37 3f 20 2d 63 20 26 71 75 6f 74 3b 41 20 56 49 52 55 53 20 49 53 20 54 41 4b 49 4e 47 20 4f 56 45 52 } //1 shutdown -s -t 7? -c &quot;A VIRUS IS TAKING OVER
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}