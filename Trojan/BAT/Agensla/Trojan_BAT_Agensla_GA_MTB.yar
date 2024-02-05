
rule Trojan_BAT_Agensla_GA_MTB{
	meta:
		description = "Trojan:BAT/Agensla.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {46 75 63 6b 69 6e 67 } //Fucking  01 00 
		$a_80_1 = {4d 6f 74 68 65 72 46 75 63 6b 65 72 42 69 74 63 68 } //MotherFuckerBitch  01 00 
		$a_80_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  01 00 
		$a_80_3 = {68 74 74 70 3a 2f 2f 6c 69 76 65 72 70 6f 6f 6c 6f 66 63 66 61 6e 63 6c 75 62 2e 63 6f 6d 2f 6c 69 76 65 72 70 6f 6f 6c } //http://liverpoolofcfanclub.com/liverpool  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Agensla_GA_MTB_2{
	meta:
		description = "Trojan:BAT/Agensla.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 41 52 43 55 53 2e 64 6c 6c } //01 00 
		$a_80_1 = {6a 61 72 69 63 6f } //jarico  01 00 
		$a_80_2 = {62 75 74 61 } //buta  01 00 
		$a_80_3 = {47 5a 69 70 53 74 72 65 61 6d } //GZipStream  01 00 
		$a_80_4 = {49 6e 76 6f 6b 65 } //Invoke  01 00 
		$a_80_5 = {47 65 74 45 6e 74 72 79 41 73 73 65 6d 62 6c 79 } //GetEntryAssembly  01 00 
		$a_80_6 = {d0 a1 d0 b5 d0 bd d1 8c d0 be d1 80 d0 b8 d1 82 d0 b0 } //Сеньорита  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Agensla_GA_MTB_3{
	meta:
		description = "Trojan:BAT/Agensla.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 2b 00 09 00 00 0a 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  0a 00 
		$a_80_1 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 } ///C choice /C Y /N /D Y /T  0a 00 
		$a_80_2 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 34 2e 30 2e 33 30 33 31 39 5c 52 65 67 41 73 6d 2e 65 78 65 } //\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe  0a 00 
		$a_80_3 = {73 63 68 74 61 73 6b 73 2e 65 78 65 } //schtasks.exe  01 00 
		$a_80_4 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //set_UseShellExecute  01 00 
		$a_80_5 = {3a 5a 6f 6e 65 2e 49 64 65 6e 74 69 66 69 65 72 } //:Zone.Identifier  01 00 
		$a_80_6 = {55 52 4c 3d 66 69 6c 65 3a 2f 2f 2f } //URL=file:///  01 00 
		$a_80_7 = {23 64 65 6c 61 79 5f 73 65 63 23 } //#delay_sec#  01 00 
		$a_80_8 = {23 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 5f 6d 65 74 68 6f 64 23 } //#installation_method#  00 00 
	condition:
		any of ($a_*)
 
}