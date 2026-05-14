
rule Trojan_BAT_Rozena_GPAU_MTB{
	meta:
		description = "Trojan:BAT/Rozena.GPAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 4f 70 65 6e 50 72 6f 63 65 73 73 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 00 2e 63 74 6f 72 } //8 捳牯楬b祓瑳浥伀橢捥t灏湥牐捯獥s楖瑲慵䅬汬捯硅圀楲整牐捯獥䵳浥牯y牃慥整敒潭整桔敲摡⸀瑣牯
	condition:
		((#a_01_0  & 1)*8) >=8
 
}