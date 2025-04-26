
rule Ransom_Win32_Babax_AB_MTB{
	meta:
		description = "Ransom:Win32/Babax.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 42 61 62 61 78 20 52 61 6e 73 6f 6d 77 61 72 65 21 } //1 All your files are encrypted by Babax Ransomware!
		$a_81_1 = {52 45 43 4f 56 45 52 59 20 49 4e 53 54 52 55 43 54 49 4f 4e 53 } //1 RECOVERY INSTRUCTIONS
		$a_81_2 = {62 61 62 61 78 52 61 6e 73 6f 6d } //1 babaxRansom
		$a_81_3 = {2e 62 61 62 61 78 65 64 } //1 .babaxed
		$a_81_4 = {74 65 6c 65 67 72 61 6d 42 6f 74 54 6f 6b 65 6e } //1 telegramBotToken
		$a_81_5 = {62 61 62 61 78 76 32 2e 65 78 65 } //1 babaxv2.exe
		$a_81_6 = {42 61 62 61 78 47 61 6e 67 } //1 BabaxGang
		$a_81_7 = {5c 42 41 42 41 58 2d 53 74 65 61 6c 65 72 5c 42 61 62 61 78 53 74 65 61 6c 65 72 20 76 32 5c 42 61 62 61 78 } //1 \BABAX-Stealer\BabaxStealer v2\Babax
		$a_81_8 = {42 61 62 61 78 4c 6f 63 6b 65 72 } //1 BabaxLocker
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=5
 
}