
rule Trojan_BAT_Diztakun_ARA_MTB{
	meta:
		description = "Trojan:BAT/Diztakun.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {77 69 6e 6c 6f 61 64 2e 70 64 62 } //02 00  winload.pdb
		$a_80_1 = {65 74 6b 6f 6e 74 72 6f 6c } //etkontrol  02 00 
		$a_80_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6d 74 61 6b 75 } //C:\ProgramData\mtaku  02 00 
		$a_80_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 77 69 6e 73 74 61 72 74 2e 65 78 65 } //C:\Windows\winstart.exe  02 00 
		$a_80_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 61 6b 63 5c 73 74 72 73 64 66 } //C:\Windows\akc\strsdf  02 00 
		$a_80_5 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6d 74 61 6b 75 5c 77 65 62 6c 69 73 74 2e 66 61 74 69 68 } //C:\ProgramData\mtaku\weblist.fatih  00 00 
	condition:
		any of ($a_*)
 
}