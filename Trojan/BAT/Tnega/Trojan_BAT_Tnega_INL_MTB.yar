
rule Trojan_BAT_Tnega_INL_MTB{
	meta:
		description = "Trojan:BAT/Tnega.INL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 38 00 37 00 33 00 36 00 37 00 30 00 30 00 30 00 36 00 30 00 37 00 30 00 37 00 33 00 38 00 39 00 35 00 38 00 2f 00 38 00 37 00 34 00 32 00 32 00 33 00 32 00 37 00 36 00 31 00 38 00 32 00 38 00 36 00 37 00 39 00 38 00 39 00 2f 00 63 00 73 00 68 00 61 00 72 00 70 00 2e 00 64 00 6c 00 6c 00 } //1 https://cdn.discordapp.com/attachments/873670006070738958/874223276182867989/csharp.dll
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_2 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //1 Form1_Load
		$a_81_3 = {31 39 38 2d 50 72 6f 74 65 63 74 6f 72 41 31 39 38 2d 50 72 6f 74 65 63 74 6f 72 } //1 198-ProtectorA198-Protector
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}