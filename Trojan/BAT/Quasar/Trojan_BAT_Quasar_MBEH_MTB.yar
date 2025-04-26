
rule Trojan_BAT_Quasar_MBEH_MTB{
	meta:
		description = "Trojan:BAT/Quasar.MBEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 64 66 66 68 68 64 66 68 64 67 67 66 68 64 66 64 66 68 64 6a 66 68 64 61 73 66 66 66 66 6b 64 66 } //1 hdffhhdfhdggfhdfdfhdjfhdasffffkdf
		$a_01_1 = {66 67 68 68 66 67 6a 73 66 66 72 66 64 66 64 66 66 66 64 66 64 73 68 66 64 73 64 66 68 } //1 fghhfgjsffrfdfdfffdfdshfdsdfh
		$a_01_2 = {73 67 66 6a 68 6a 66 66 66 67 72 66 68 64 64 66 68 66 66 66 61 64 66 73 66 73 73 63 66 67 64 62 } //1 sgfjhjfffgrfhddfhfffadfsfsscfgdb
		$a_01_3 = {6b 66 64 66 73 6a 67 67 66 66 66 68 } //1 kfdfsjggfffh
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}