
rule Trojan_BAT_Netwire_TSQ_MTB{
	meta:
		description = "Trojan:BAT/Netwire.TSQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_81_0 = {6b 6f 74 61 64 69 61 69 6e 63 2e 63 6f 6d } //10 kotadiainc.com
		$a_81_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_81_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_3 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_81_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_5 = {52 65 61 64 42 79 74 65 73 } //1 ReadBytes
		$a_81_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=16
 
}