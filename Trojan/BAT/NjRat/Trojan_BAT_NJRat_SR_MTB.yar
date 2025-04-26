
rule Trojan_BAT_NJRat_SR_MTB{
	meta:
		description = "Trojan:BAT/NJRat.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_81_0 = {45 78 63 65 70 74 69 6f 6e 61 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d } //1 Exceptiona firewall delete allowedprogram
		$a_81_1 = {2f 63 20 70 69 6e 67 20 30 20 2d 6e 20 32 20 26 20 64 65 6c } //1 /c ping 0 -n 2 & del
		$a_81_2 = {64 75 63 6b 61 70 70 2e 64 75 63 6b 64 6e 73 2e 6f 72 67 } //1 duckapp.duckdns.org
		$a_81_3 = {5c 6c 6f 67 2e 74 78 74 } //1 \log.txt
		$a_81_4 = {48 41 43 4b 49 54 55 50 } //1 HACKITUP
		$a_81_5 = {43 6f 25 6e 65 63 74 } //1 Co%nect
		$a_81_6 = {23 79 73 74 65 6d 24 72 69 76 65 } //1 #ystem$rive
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=5
 
}