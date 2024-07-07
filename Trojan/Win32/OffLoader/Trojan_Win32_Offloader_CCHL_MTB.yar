
rule Trojan_Win32_Offloader_CCHL_MTB{
	meta:
		description = "Trojan:Win32/Offloader.CCHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {63 6c 61 6d 62 69 72 74 68 2e 73 69 74 65 2f 62 61 6c 6c 2e 70 68 70 3f } //5 clambirth.site/ball.php?
		$a_81_1 = {62 6f 6f 6b 61 70 70 61 72 61 74 75 73 2e 6f 6e 6c 69 6e 65 2f 74 72 61 63 6b 65 72 2f 74 68 61 6e 6b 5f 79 6f 75 2e 70 68 70 3f } //5 bookapparatus.online/tracker/thank_you.php?
		$a_81_2 = {63 6f 6d 6d 69 74 74 65 65 6f 66 66 65 72 2e 77 65 62 73 69 74 65 2f 61 6c 6c 2e 70 68 70 3f } //5 committeeoffer.website/all.php?
		$a_81_3 = {76 69 65 77 63 6c 6f 74 68 2e 6f 6e 6c 69 6e 65 2f 74 72 61 63 6b 65 72 2f 74 68 61 6e 6b 5f 79 6f 75 2e 70 68 70 3f } //5 viewcloth.online/tracker/thank_you.php?
		$a_81_4 = {6a 61 6d 63 61 62 62 61 67 65 2e 6f 6e 6c 69 6e 65 2f 74 68 61 6e 6b 79 6f 75 2e 70 68 70 3f } //5 jamcabbage.online/thankyou.php?
		$a_81_5 = {2f 73 69 6c 65 6e 74 } //1 /silent
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*5+(#a_81_4  & 1)*5+(#a_81_5  & 1)*1) >=5
 
}