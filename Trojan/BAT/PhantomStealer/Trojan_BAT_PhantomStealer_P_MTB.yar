
rule Trojan_BAT_PhantomStealer_P_MTB{
	meta:
		description = "Trojan:BAT/PhantomStealer.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 6c 69 70 62 6f 61 72 64 2e 6a 70 67 } //1 Clipboard.jpg
		$a_81_1 = {52 44 50 5f 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 RDP_Passwords.txt
		$a_81_2 = {77 61 6c 6c 65 74 2e 64 61 74 } //1 wallet.dat
		$a_81_3 = {41 6e 79 44 65 73 6b 5f 49 44 2e 74 78 74 } //1 AnyDesk_ID.txt
		$a_81_4 = {50 68 61 6e 74 6f 6d 20 53 74 65 61 6c 65 72 } //1 Phantom Stealer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}