
rule Trojan_Win64_Lazy_BXS_MTB{
	meta:
		description = "Trojan:Win64/Lazy.BXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {63 72 65 61 74 65 64 20 62 79 20 4d 6f 69 78 64 20 73 74 65 61 6c 65 72 } //1 created by Moixd stealer
		$a_81_1 = {6d 6f 69 78 64 2d } //1 moixd-
		$a_81_2 = {46 69 6c 65 20 6d 61 72 6b 65 72 20 40 61 74 6f 6e 79 38 33 38 36 36 } //1 File marker @atony83866
		$a_81_3 = {5c 67 6f 6f 67 6c 65 5c 63 68 72 6f 6d 65 20 62 65 74 61 } //1 \google\chrome beta
		$a_81_4 = {53 4f 46 54 57 41 52 45 5c 43 6c 69 65 6e 74 73 5c 53 74 61 72 74 4d 65 6e 75 49 6e 74 65 72 6e 65 74 5c 47 6f 6f 67 6c 65 20 43 68 72 6f 6d 65 20 42 65 74 61 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //1 SOFTWARE\Clients\StartMenuInternet\Google Chrome Beta\shell\open\command
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}