
rule Trojan_MacOS_Pwnet_B_MTB{
	meta:
		description = "Trojan:MacOS/Pwnet.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 44 65 73 6b 74 6f 70 2f 70 77 6e 65 64 6e 65 74 2f 70 77 6e 65 64 6e 65 74 2f 70 77 6e 65 64 6e 65 74 2f } //01 00  /Desktop/pwnednet/pwnednet/pwnednet/
		$a_00_1 = {63 6f 6d 2e 64 79 6e 61 6d 73 6f 66 74 2e 57 65 62 48 65 6c 70 65 72 } //01 00  com.dynamsoft.WebHelper
		$a_01_2 = {2f 70 72 69 76 61 74 65 2f 2e 74 72 61 73 68 2f 2e 61 73 73 65 74 73 2f 68 65 6c 70 65 72 2e 7a 69 70 } //01 00  /private/.trash/.assets/helper.zip
		$a_00_3 = {69 6e 73 74 61 6c 6c 4d 69 6e 65 72 45 76 } //00 00  installMinerEv
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}