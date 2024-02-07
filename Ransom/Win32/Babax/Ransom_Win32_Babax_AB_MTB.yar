
rule Ransom_Win32_Babax_AB_MTB{
	meta:
		description = "Ransom:Win32/Babax.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 42 61 62 61 78 20 52 61 6e 73 6f 6d 77 61 72 65 21 } //01 00  All your files are encrypted by Babax Ransomware!
		$a_81_1 = {52 45 43 4f 56 45 52 59 20 49 4e 53 54 52 55 43 54 49 4f 4e 53 } //01 00  RECOVERY INSTRUCTIONS
		$a_81_2 = {62 61 62 61 78 52 61 6e 73 6f 6d } //01 00  babaxRansom
		$a_81_3 = {2e 62 61 62 61 78 65 64 } //01 00  .babaxed
		$a_81_4 = {74 65 6c 65 67 72 61 6d 42 6f 74 54 6f 6b 65 6e } //01 00  telegramBotToken
		$a_81_5 = {62 61 62 61 78 76 32 2e 65 78 65 } //01 00  babaxv2.exe
		$a_81_6 = {42 61 62 61 78 47 61 6e 67 } //01 00  BabaxGang
		$a_81_7 = {5c 42 41 42 41 58 2d 53 74 65 61 6c 65 72 5c 42 61 62 61 78 53 74 65 61 6c 65 72 20 76 32 5c 42 61 62 61 78 } //01 00  \BABAX-Stealer\BabaxStealer v2\Babax
		$a_81_8 = {42 61 62 61 78 4c 6f 63 6b 65 72 } //00 00  BabaxLocker
		$a_00_9 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}