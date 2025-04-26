
rule TrojanDownloader_O97M_Valyria_RHAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Valyria.RHAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {28 22 73 65 74 6f 62 6a 73 68 65 6c 6c 3d 77 73 63 72 69 70 74 2e 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 22 29 22 29 } //1 ("setobjshell=wscript.createobject(""wscript.shell"")")
		$a_01_1 = {28 22 63 6f 6d 6d 61 6e 64 3d 22 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 77 69 6e 64 6f 77 73 70 6f 77 65 72 73 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 2d 77 69 6e 64 6f 77 73 74 79 6c 65 68 69 64 64 65 6e 2d 6e 6f 70 2d 6e 6f 65 78 69 74 2d 63 69 65 78 28 28 6e 65 77 2d 6f 62 6a 65 63 74 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 } //1 ("command=""c:\windows\system32\windowspowershell\v1.0\powershell.exe-windowstylehidden-nop-noexit-ciex((new-objectnet.webclient)
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 65 6e 69 67 6d 61 30 78 33 2f 67 65 6e 65 72 61 74 65 2d 6d 61 63 72 6f 2f 6d 61 73 74 65 72 2f 67 65 6e 65 72 61 74 65 2d 6d 61 63 72 6f 2e 70 73 31 27 29 29 } //1 downloadstring('https://raw.githubusercontent.com/enigma0x3/generate-macro/master/generate-macro.ps1'))
		$a_01_3 = {69 6e 76 6f 6b 65 2d 73 68 65 6c 6c 63 6f 64 65 2d 70 61 79 6c 6f 61 64 77 69 6e 64 6f 77 73 2f 6d 65 74 65 72 70 72 65 74 65 72 2f 72 65 76 65 72 73 65 5f 68 74 74 70 73 2d 6c 68 6f 73 74 31 37 32 2e 31 39 2e 32 34 30 2e 31 32 34 2d 6c 70 6f 72 74 31 32 33 34 2d 66 6f 72 63 65 22 22 22 29 } //1 invoke-shellcode-payloadwindows/meterpreter/reverse_https-lhost172.19.240.124-lport1234-force""")
		$a_01_4 = {77 72 69 74 65 6c 69 6e 65 28 22 6f 62 6a 73 68 65 6c 6c 2e 72 75 6e 63 6f 6d 6d 61 6e 64 2c 30 22 29 } //1 writeline("objshell.runcommand,0")
		$a_01_5 = {77 73 63 72 69 70 74 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 63 6f 6e 66 69 67 2e 76 62 73 } //1 wscriptc:\users\public\config.vbs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}