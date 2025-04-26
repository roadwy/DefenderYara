
rule Trojan_Win64_Barys_RD_MTB{
	meta:
		description = "Trojan:Win64/Barys.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 73 6f 61 72 65 5c 44 65 73 6b 74 6f 70 5c 58 62 65 73 74 20 50 72 69 6d 65 20 78 78 5c 58 62 65 73 74 20 50 72 69 6d 65 20 78 78 5c 65 78 61 6d 70 6c 65 73 5c 45 78 65 5c 58 62 65 73 74 20 50 72 69 6d 65 2e 70 64 62 } //1 C:\Users\soare\Desktop\Xbest Prime xx\Xbest Prime xx\examples\Exe\Xbest Prime.pdb
		$a_01_1 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 72 75 6c 65 20 6e 61 6d 65 3d 61 6c 6c 20 70 72 6f 67 72 61 6d 3d 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 42 6c 75 65 53 74 61 63 6b 73 5c 48 44 2d 50 6c 61 79 65 72 2e 65 78 65 } //1 netsh advfirewall firewall delete rule name=all program="%ProgramFiles%\BlueStacks\HD-Player.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}