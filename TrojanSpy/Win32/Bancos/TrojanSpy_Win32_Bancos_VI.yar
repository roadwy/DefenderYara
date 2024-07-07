
rule TrojanSpy_Win32_Bancos_VI{
	meta:
		description = "TrojanSpy:Win32/Bancos.VI,SIGNATURE_TYPE_PEHSTR,07 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //1 SOFTWARE\Borland\Delphi
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2d 66 20 2d 69 6d 20 } //1 taskkill.exe -f -im 
		$a_01_2 = {42 41 43 4b 53 50 41 43 45 } //1 BACKSPACE
		$a_01_3 = {74 65 78 74 20 74 69 74 6c 65 3d } //1 text title=
		$a_01_4 = {73 65 6e 64 6d 61 69 6c } //1 sendmail
		$a_01_5 = {25 40 25 68 25 6f 25 74 25 6d 25 61 25 69 25 6c 25 2e 25 63 25 6f 25 6d 25 } //1 %@%h%o%t%m%a%i%l%.%c%o%m%
		$a_01_6 = {57 25 69 25 6e 25 64 25 6f 25 77 25 73 25 20 25 4c 25 69 25 76 25 65 25 20 25 4d 25 65 25 73 25 73 25 65 25 6e 25 67 25 65 25 72 25 } //1 W%i%n%d%o%w%s% %L%i%v%e% %M%e%s%s%e%n%g%e%r%
		$a_01_7 = {74 6d 72 42 75 73 63 61 4d 53 4e 54 } //1 tmrBuscaMSNT
		$a_01_8 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //1 Internet Explorer_Server
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}