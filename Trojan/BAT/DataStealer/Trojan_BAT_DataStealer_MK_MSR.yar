
rule Trojan_BAT_DataStealer_MK_MSR{
	meta:
		description = "Trojan:BAT/DataStealer.MK!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 75 32 37 32 39 2e 6d 68 30 2e 72 75 2f } //http://u2729.mh0.ru/  5
		$a_80_1 = {62 72 6f 77 73 65 72 50 61 73 73 77 6f 72 64 73 } //browserPasswords  1
		$a_80_2 = {50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //Passwords.txt  1
		$a_80_3 = {46 69 72 65 46 6f 78 5c 6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //FireFox\logins.json  1
		$a_80_4 = {43 72 65 64 69 74 43 61 72 64 73 2e 74 78 74 } //CreditCards.txt  1
		$a_80_5 = {46 69 6c 65 7a 69 6c 6c 61 5c 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //Filezilla\Passwords.txt  1
		$a_80_6 = {56 50 4e 5c 50 72 6f 74 6f 6e 56 50 4e 5c 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //VPN\ProtonVPN\Passwords.txt  1
		$a_80_7 = {50 73 69 5c 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //Psi\Passwords.txt  1
		$a_80_8 = {50 69 64 67 69 6e 5c 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //Pidgin\Passwords.txt  1
		$a_80_9 = {42 69 74 63 6f 69 6e 43 6f 72 65 5c 77 61 6c 6c 65 74 2e 64 61 74 } //BitcoinCore\wallet.dat  1
		$a_80_10 = {44 61 73 68 43 6f 72 65 5c 77 61 6c 6c 65 74 2e 64 61 74 } //DashCore\wallet.dat  1
		$a_80_11 = {4c 69 74 65 63 6f 69 6e 43 6f 72 65 5c 77 61 6c 6c 65 74 2e 64 61 74 } //LitecoinCore\wallet.dat  1
		$a_80_12 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //SELECT * FROM Win32_OperatingSystem  1
		$a_80_13 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 42 49 4f 53 } //SELECT * FROM Win32_BIOS  1
		$a_80_14 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //Select * from Win32_ComputerSystem  1
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1) >=15
 
}