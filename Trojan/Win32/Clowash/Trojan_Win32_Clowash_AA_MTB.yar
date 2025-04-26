
rule Trojan_Win32_Clowash_AA_MTB{
	meta:
		description = "Trojan:Win32/Clowash.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 3a 5c 43 6f 6e 74 72 6f 6c 6c 65 72 5c 53 63 61 6c 69 6e 67 5c 70 69 6e 67 5c 6d 69 64 64 6c 65 77 61 72 65 5c 73 79 6e 63 68 72 6f 6e 69 7a 61 5c 78 36 34 5c 72 65 6c 65 61 73 65 5c 63 6c 6f 63 6b 5c 5a 5c 63 6c 69 2e 70 64 62 } //1 t:\Controller\Scaling\ping\middleware\synchroniza\x64\release\clock\Z\cli.pdb
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c 20 2f 46 20 2f 51 20 22 25 73 22 } //1 cmd.exe /c del /F /Q "%s"
		$a_01_2 = {5b 6e 6f 73 65 72 76 69 63 65 7c 63 6f 6e 73 6f 6c 65 7c 73 74 61 72 74 7c 73 74 6f 70 7c 69 6e 73 74 61 6c 6c 7c 72 65 6d 6f 76 65 7c 72 75 6e 6e 69 6e 67 7c 73 74 61 74 75 73 5d } //1 [noservice|console|start|stop|install|remove|running|status]
		$a_01_3 = {4e 00 65 00 74 00 63 00 75 00 74 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 20 00 41 00 6e 00 74 00 69 00 20 00 41 00 52 00 50 00 20 00 53 00 70 00 6f 00 6f 00 66 00 20 00 4b 00 65 00 72 00 6e 00 61 00 6c 00 } //1 Netcut Defender Anti ARP Spoof Kernal
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}