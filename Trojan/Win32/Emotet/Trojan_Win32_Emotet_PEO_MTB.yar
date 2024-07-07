
rule Trojan_Win32_Emotet_PEO_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {49 81 c9 00 ff ff ff 41 0f b6 44 0c 90 01 01 8b 4c 24 90 01 01 32 04 19 83 c3 01 83 6c 24 90 01 01 01 88 43 ff 90 00 } //1
		$a_81_1 = {51 34 36 45 50 49 34 43 67 6e 46 39 36 6f 6b 31 37 40 55 6c 65 52 25 73 40 24 77 59 44 58 51 4f 6a 38 76 40 7d 5a 6c 79 71 41 37 59 7e 56 75 7e 7a 51 24 2a 49 42 24 4c 50 46 4d 32 } //1 Q46EPI4CgnF96ok17@UleR%s@$wYDXQOj8v@}ZlyqA7Y~Vu~zQ$*IB$LPFM2
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}