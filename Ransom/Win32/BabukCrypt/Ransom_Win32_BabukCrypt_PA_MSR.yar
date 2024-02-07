
rule Ransom_Win32_BabukCrypt_PA_MSR{
	meta:
		description = "Ransom:Win32/BabukCrypt.PA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 20 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //01 00  /c vssadmin.exe delete shadows /all /quiet
		$a_80_1 = {62 61 62 75 6b 20 72 61 6e 73 6f 6d 77 61 72 65 } //babuk ransomware  01 00 
		$a_01_2 = {2e 00 62 00 61 00 62 00 79 00 6b 00 } //01 00  .babyk
		$a_01_3 = {5c 00 48 00 6f 00 77 00 20 00 54 00 6f 00 20 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 20 00 59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //00 00  \How To Restore Your Files.txt
	condition:
		any of ($a_*)
 
}